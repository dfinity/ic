pub mod error;
mod slot_mgr;

use ic_sys::PAGE_SIZE;
use libc::{
    c_void, mmap, mprotect, munmap, MAP_ANON, MAP_FAILED, MAP_FIXED, MAP_NORESERVE, MAP_PRIVATE,
    MAP_SHARED, PROT_NONE, PROT_READ, PROT_WRITE,
};

#[cfg(target_os = "linux")]
use ic_sys::IS_WSL;

use std::{
    collections::HashMap,
    fmt,
    fs::{File, OpenOptions},
    io::Error,
    marker::PhantomData,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
    ptr,
    sync::{atomic::*, Arc},
};
#[macro_use]
extern crate lazy_static;
use parking_lot::*;

lazy_static! {
    static ref SLOT_MGR_LIST: parking_lot::RwLock<HashMap<PathBuf, Arc<SlotMgr>>> =
        parking_lot::RwLock::new(HashMap::new());
}

use crate::{error::*, slot_mgr::*};
use enum_dispatch::*;
use ic_utils::ic_features::*;
use num_integer::*;

const KB: u64 = 1024;
#[cfg(not(test))]
const MB: u64 = KB * KB;
#[cfg(not(test))]
const GB: u64 = MB * KB;

//Note: Following arrangement is temporary
const META_OFFSET: u64 = 0; // 0th page for metadata
const META_LEN: usize = 1; // 1 page size for metadata

const GLOBALS_OFFSET: u64 = META_LEN as u64; // first page
const GLOBALS_LEN: usize = 1; // 1 page size for globals

const HEAP_OFFSET: u64 = GLOBALS_OFFSET as u64 + GLOBALS_LEN as u64;
#[cfg(not(test))]
const HEAP_LEN: usize = 2 * 1024 * 1024; // 2Million pages ~ 8GB

const STATE_MAGIC: u64 = 0x0044_4649_4e49_5459;
const STATE_VERSION: u64 = 0x1;

#[cfg(not(test))]
const MAX_ROUNDS: u32 = 520;

#[cfg(not(test))]
// Default headroom space assumed as written to trigger grow
const INITIAL_WRITTEN_SIZE: usize = 4 * GB as usize;

#[cfg(not(test))]
const INITIAL_FILE_SIZE: usize = 6 * GB as usize;

#[cfg(not(test))]
// If free space is less than GROW_THRESHOLD it will trigger
// the file grow
const GROW_THRESHOLD: usize = GB as usize;

#[cfg(not(test))]
// File size increment to grow the state file by
const GROW_SIZE: usize = 10 * GB as usize;

pub trait AccessPolicy {}
pub trait ReadOnlyPolicy: AccessPolicy {}
pub trait ReadWritePolicy: AccessPolicy {}
#[derive(Clone)]
pub enum ReadOnly {}
#[derive(Clone)]
pub enum ReadWrite {}

impl AccessPolicy for ReadOnly {}
impl ReadOnlyPolicy for ReadOnly {}

impl AccessPolicy for ReadWrite {}
impl ReadWritePolicy for ReadWrite {}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct StateMeta {
    magic: u64,
    version: u64,
    meta_offset: u64,
    meta_len: usize,
    globals_offset: u64,
    globals_len: usize,
    heap_offset: u64,
    heap_len: usize,
}

impl Default for StateMeta {
    fn default() -> Self {
        Self {
            magic: 0,
            version: 0,
            meta_offset: 0,
            meta_len: 0,
            globals_offset: 0,
            globals_len: 0,
            heap_offset: 0,
            heap_len: 0,
        }
    }
}

#[enum_dispatch]
pub trait MappedState: Send {
    /// Returns the base of memory region where canister
    /// heap begins.
    fn get_heap_base(&self) -> *mut u8;

    /// Returns the max heap len when the heap
    /// was first initialized.
    fn get_heap_len(&self) -> usize;

    /// Resets the permission on the heap
    /// based on the type
    fn make_heap_accessible(&self);

    /// Returns slice of globals memory associated
    /// with this mapped_state.
    fn get_globals(&self) -> &[u8];

    /// Update the globals memory with new globals.
    fn update_globals(&self, _encoded_globals: &[u8]) {
        unimplemented!("Updates of globals is not supported for readonly CowMemoryManager");
    }

    /// soft_commit ensures that all modified pages (mutations) represented by
    /// pages slice become part of the "current" state. This
    /// means even after MappedState object is dropped, mutations will be
    /// reflected in subsequent MappedState object and can eventually become
    /// part of some round. Mutations not soft_committed have a lifetime of
    /// MappedState object and will disappear once MappedState object is
    /// dropped.
    fn soft_commit(&self, _pages: &[u64]) {
        unimplemented!("Soft-committing not supported for readonly CowMemoryManager");
    }

    /// Using update_heap_page, individual heap pages can be modified. This is
    /// useful during canister installation to patch up initial pages.
    /// Once the heap is modified, soft_commit is necessary to ensure that the
    /// modifications become part of "current" state.
    fn update_heap_page(&self, _page_idx: u64, _bytes: &[u8]) {
        unimplemented!("Heap updates not supported for readonly CowMemoryManager");
    }

    fn copy_to_heap(&self, _offset: u64, _bytes: &[u8]) -> Vec<u64> {
        unimplemented!("Heap updates not supported for readonly CowMemoryManager");
    }

    fn copy_from_heap(&self, _offset: u64, _len: u64) -> &[u8];

    fn clear(&self) {
        unimplemented!("Heap reset not supported for readonly CowMemoryManager");
    }
}

#[enum_dispatch(MappedState)]
enum MappedStates {
    ReadOnly(MappedStateCommon<ReadOnly>),
    ReadWrite(MappedStateCommon<ReadWrite>),
}

impl MappedStates {
    fn unmap(&mut self) {
        match self {
            Self::ReadOnly(mapped_state) => mapped_state.unmap(),
            Self::ReadWrite(mapped_state) => mapped_state.unmap(),
        }
    }
}

struct MapInfo {
    mapped_base: u64,
    mapped_len: usize,
    file: File,
    state_root: PathBuf,
    current_mappings: SlotMappings,
    written_so_far: Arc<AtomicUsize>,
}

struct MappedStateCommon<T> {
    meta: StateMeta,
    map_info: MapInfo,
    _marker: PhantomData<T>,
}

pub struct MappedStateImpl {
    mapped_state: MappedStates,
}

impl<T: AccessPolicy> MappedStateCommon<T> {
    fn get_mapped_base(&self) -> *mut u8 {
        self.map_info.mapped_base as *mut u8
    }

    fn get_heap_base(&self) -> *mut u8 {
        unsafe {
            self.get_mapped_base()
                .add(self.meta.heap_offset as usize * PAGE_SIZE)
        }
    }

    fn get_heap_len(&self) -> usize {
        if let Some(last_lba) = self.map_info.current_mappings.get_last_slot() {
            (last_lba - HEAP_OFFSET) as usize * PAGE_SIZE
        } else {
            0
        }
    }

    fn get_globals_base(&self) -> *mut u8 {
        unsafe {
            self.get_mapped_base()
                .add(self.meta.globals_offset as usize * PAGE_SIZE)
        }
    }

    fn get_globals_len(&self) -> usize {
        self.meta.globals_len * PAGE_SIZE
    }

    fn get_globals(&self) -> &[u8] {
        unsafe {
            let globals_base = self.get_globals_base();
            reset_mem_protection(globals_base, self.get_globals_len(), PROT_READ | PROT_WRITE);
            std::slice::from_raw_parts(self.get_globals_base() as *const u8, self.get_globals_len())
        }
    }

    fn unmap(&mut self) {
        if self.map_info.mapped_len > 0 {
            unsafe {
                let rc = munmap(
                    self.map_info.mapped_base as *mut c_void,
                    self.map_info.mapped_len,
                );
                assert_eq!(rc, 0, "munmap failed: {}", Error::last_os_error());
            }
            self.map_info.mapped_len = 0;
        }
    }

    fn soft_commit(&self, pages: &[u64]) {
        let written_so_far = self.map_info.written_so_far.load(Ordering::Relaxed);
        let to_write = pages.len() * PAGE_SIZE;
        let file_len = self.map_info.file.metadata().unwrap().len() as usize;

        // if we will blow through the current file size after handling
        // this write, lets increase the file first
        if file_len <= written_so_far + to_write + GROW_THRESHOLD {
            self.map_info
                .file
                .set_len((file_len + GROW_SIZE) as u64)
                .expect("Unable to grow file");
        }

        let slot_mgr = get_slot_mgr(&self.map_info.state_root);

        let mut mappings_to_put = HashMap::new();

        let raw_fd = self.map_info.file.as_raw_fd();

        #[cfg(target_os = "linux")]
        let (rpipe, wpipe) = nix::unistd::pipe().unwrap();

        #[cfg(target_os = "linux")]
        // Max 1MB pipe size
        nix::fcntl::fcntl(wpipe, nix::fcntl::FcntlArg::F_SETPIPE_SZ(1024 * 1024))
            .expect("Unable to set pipe size");

        // allocate all slots in 1 go to minimize transactions
        let mut allocated_slots = slot_mgr.alloc_free_slots(pages.len() as u32);
        for page_num in pages.iter() {
            let heap_page = *page_num;
            let offset = heap_page as usize * PAGE_SIZE;

            let (is_shared, existing_pba) = self.map_info.current_mappings.get_slot_info(heap_page);

            let slot_to_use = if is_shared {
                allocated_slots.remove(0)
            } else {
                existing_pba
            };

            // dont overwrite physical metapage
            let what_to_map = (slot_to_use + self.meta.meta_len as u64) * PAGE_SIZE as u64;
            #[cfg(target_os = "linux")]
            let mut copied = false;
            #[cfg(not(target_os = "linux"))]
            let copied = false;

            #[cfg(target_os = "linux")]
            if !*IS_WSL {
                // On linux copying of memory to files can be accomplished using splicing.
                // It is very efficient approach and avoids user/kernel & kernel/kernel copy
                // overheads. Instead of copying page contents, splicing
                // presents opportunity to kernel to "move" pages using
                // refcounting and other accounting magic.

                // Here by "gifting" the pages we are letting kernel know that we no longer
                // want to own the "private pages". Kernel simply "moves" them into page cache
                // making the dirty data part of the heap file without paying copy penalty.

                // https://en.wikipedia.org/wiki/Splice_(system_call)
                // https://web.archive.org/web/20130521163124/http://kerneltrap.org/node/6505
                unsafe {
                    let vec = nix::sys::uio::IoVec::from_slice(::std::slice::from_raw_parts(
                        self.get_mapped_base().add(offset),
                        PAGE_SIZE,
                    ));

                    nix::fcntl::vmsplice(wpipe, &[vec], nix::fcntl::SpliceFFlags::SPLICE_F_GIFT)
                        .unwrap_or_else(|_| {
                            panic!(
                                "Unable to vmsplice {:x} pages len {} {:?}",
                                self.get_mapped_base().add(offset) as u64,
                                pages.len(),
                                pages
                            )
                        });
                    nix::fcntl::splice(
                        rpipe,
                        None,
                        raw_fd,
                        Some(&mut (what_to_map as i64)),
                        PAGE_SIZE,
                        nix::fcntl::SpliceFFlags::SPLICE_F_MOVE,
                    )
                    .expect("splice failed");
                }
                copied = true;
            }

            // The following works on both OS X and WSL.
            if !copied {
                unsafe {
                    let dst = mmap(
                        ptr::null_mut(),
                        PAGE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        raw_fd,
                        what_to_map as i64,
                    );
                    if dst == MAP_FAILED {
                        panic!("mmap failed: {}", Error::last_os_error());
                    }

                    let src = self.get_mapped_base().add(offset);
                    ptr::copy_nonoverlapping(src as *mut c_void, dst as *mut c_void, PAGE_SIZE);

                    munmap(dst, PAGE_SIZE);
                }
            }

            if is_shared {
                mappings_to_put.insert(heap_page, (slot_to_use, existing_pba));
            }
        }

        #[cfg(target_os = "linux")]
        {
            let _ = nix::unistd::close(rpipe);
            let _ = nix::unistd::close(wpipe);
        }

        // free slots that we didnt use
        slot_mgr.free_unused_slots(allocated_slots);

        // Account all the new writes so far
        let written = self.map_info.written_so_far.load(Ordering::Relaxed)
            + mappings_to_put.len() * PAGE_SIZE;

        self.map_info
            .written_so_far
            .store(written, Ordering::Relaxed);

        // put all mappings in one go
        slot_mgr.put_all_mappings(mappings_to_put);
    }

    fn copy_from_heap(&self, offset: u64, len: u64) -> &[u8] {
        unsafe {
            let base = self.get_heap_base().add(offset as usize);
            reset_mem_protection(base, len as usize, PROT_READ);
            std::slice::from_raw_parts(base as *const u8, len as usize)
        }
    }
}

impl MappedState for MappedStateCommon<ReadOnly> {
    fn get_heap_base(&self) -> *mut u8 {
        self.get_heap_base()
    }

    fn get_heap_len(&self) -> usize {
        self.get_heap_len()
    }

    fn make_heap_accessible(&self) {
        reset_mem_protection(self.get_heap_base(), self.get_heap_len(), PROT_READ);
    }

    fn get_globals(&self) -> &[u8] {
        self.get_globals()
    }

    fn copy_from_heap(&self, offset: u64, len: u64) -> &[u8] {
        self.copy_from_heap(offset, len)
    }
}

impl MappedState for MappedStateCommon<ReadWrite> {
    fn get_heap_base(&self) -> *mut u8 {
        self.get_heap_base()
    }

    fn get_heap_len(&self) -> usize {
        self.get_heap_len()
    }

    fn make_heap_accessible(&self) {
        reset_mem_protection(
            self.get_heap_base(),
            self.get_heap_len(),
            PROT_READ | PROT_WRITE,
        );
    }

    fn get_globals(&self) -> &[u8] {
        self.get_globals()
    }

    fn update_globals(&self, encoded_globals: &[u8]) {
        if encoded_globals.len() > self.get_globals_len() {
            panic!("globals too big, cannot be persisted");
        }

        unsafe {
            let dst = self.get_globals_base();
            reset_mem_protection(dst, encoded_globals.len(), PROT_READ | PROT_WRITE);
            std::ptr::copy_nonoverlapping(encoded_globals.as_ptr(), dst, encoded_globals.len());
        }
        self.soft_commit(&[self.meta.globals_offset]);
    }

    fn soft_commit(&self, pages: &[u64]) {
        let heap_pages: Vec<u64> = pages
            .iter()
            .map(|page| page + self.meta.heap_offset)
            .collect();
        self.soft_commit(&heap_pages)
    }

    fn copy_to_heap(&self, offset: u64, bytes: &[u8]) -> Vec<u64> {
        let len_to_copy = bytes.len();
        let heap_base = self.get_heap_base() as u64;
        let copy_base = heap_base + offset;
        let page_size = PAGE_SIZE as u64;

        // find the aligned base address to reset the permissions from
        let aligned_base = (copy_base).prev_multiple_of(&page_size);
        let total_len = (copy_base + len_to_copy as u64) - aligned_base;

        reset_mem_protection(
            aligned_base as *mut u8,
            total_len as usize,
            PROT_READ | PROT_WRITE,
        );

        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), copy_base as *mut u8, len_to_copy) }

        let start_page = (aligned_base - heap_base) / page_size;
        let nr_pages = (total_len).div_ceil(&page_size);

        (0..nr_pages).map(|p| p + start_page).collect()
    }

    fn update_heap_page(&self, page_idx: u64, bytes: &[u8]) {
        let offset = page_idx as usize * PAGE_SIZE;
        assert!(bytes.len().is_multiple_of(&PAGE_SIZE));
        unsafe {
            let dst = self.get_heap_base().add(offset);
            reset_mem_protection(dst, PAGE_SIZE, PROT_READ | PROT_WRITE);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, PAGE_SIZE);
        };
    }

    fn copy_from_heap(&self, offset: u64, len: u64) -> &[u8] {
        self.copy_from_heap(offset, len)
    }

    fn clear(&self) {
        let slot_mgr = get_slot_mgr(&self.map_info.state_root);
        slot_mgr.clear_current();
    }
}

impl MappedState for MappedStateImpl {
    fn get_heap_base(&self) -> *mut u8 {
        self.mapped_state.get_heap_base()
    }

    fn get_heap_len(&self) -> usize {
        self.mapped_state.get_heap_len()
    }

    fn make_heap_accessible(&self) {
        self.mapped_state.make_heap_accessible();
    }

    fn get_globals(&self) -> &[u8] {
        self.mapped_state.get_globals()
    }

    fn update_globals(&self, encoded_globals: &[u8]) {
        self.mapped_state.update_globals(encoded_globals);
    }

    fn soft_commit(&self, pages: &[u64]) {
        self.mapped_state.soft_commit(pages);
    }

    fn update_heap_page(&self, page_idx: u64, bytes: &[u8]) {
        self.mapped_state.update_heap_page(page_idx, bytes);
    }

    fn copy_to_heap(&self, offset: u64, bytes: &[u8]) -> Vec<u64> {
        self.mapped_state.copy_to_heap(offset, bytes)
    }

    fn copy_from_heap(&self, offset: u64, len: u64) -> &[u8] {
        self.mapped_state.copy_from_heap(offset, len)
    }

    fn clear(&self) {
        self.mapped_state.clear()
    }
}

impl Drop for MappedStateImpl {
    fn drop(&mut self) {
        self.mapped_state.unmap();
    }
}

#[enum_dispatch]
pub trait CowMemoryManager {
    /// get_map returns a MappedState representing "current" mapped state
    /// of the canister (heap and globals for time being). This state can be
    /// used for example during canister execution and can be freely mutated.
    /// "current_state" can be updated with mutations by calling "soft_commmit".
    fn get_map(&self) -> MappedStateImpl;

    /// get_map_for_snapshot returns a MappedState representing in memory mapped
    /// state of canister (heap and globals for time being) at the end of a
    /// specific round. This state, although can be freely mutated, the
    /// mutations cannot be made part round state using "soft_commit".
    /// MappedState returned by get_map_for_snapshot can be used for query type
    /// canister operations.
    fn get_map_for_snapshot(&self, _round_to_use: u64) -> Result<MappedStateImpl, CowError>;

    /// create_snapshot creates a snapshot of all soft_committed mutations to
    /// canister state the last snapshot
    fn create_snapshot(&self, end_round: u64);

    /// checkpoint primarily ensures slot_mgr's internal metadata is flushed to
    /// disk Collapsing older rounds would be added here later.
    fn checkpoint(&self);

    /// Reset's canister's "current" state to "vanilla" initial state.
    fn upgrade(&self);

    fn is_valid(&self) -> bool;

    fn remove_states_below(&self, round: u64);
}

fn reset_mem_protection(base: *mut u8, len: usize, new_permissions: libc::c_int) {
    unsafe {
        let page_size = PAGE_SIZE as u64;

        // find the aligned base address to reset the permissions from
        let aligned_base = (base as u64).prev_multiple_of(&page_size);
        let total_len = (base as u64 + len as u64) - aligned_base;

        let result = mprotect(
            aligned_base as *mut c_void,
            total_len as usize,
            new_permissions,
        );

        assert_eq!(
            result,
            0,
            "mprotect failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[enum_dispatch(CowMemoryManager)]
#[derive(Clone, Debug)]
pub enum CowMemoryManagerImpl {
    ReadOnly(CowMemoryManagerCommon<ReadOnly>),
    ReadWrite(CowMemoryManagerCommon<ReadWrite>),
}

impl CowMemoryManagerImpl {
    pub fn open_readonly(state_root: PathBuf) -> Self {
        if Self::is_cow(&state_root) {
            Self::ReadOnly(CowMemoryManagerCommon::<ReadOnly>::open(state_root))
        } else {
            Self::ReadOnly(CowMemoryManagerCommon::<ReadOnly>::open_fake())
        }
    }

    pub fn open_readwrite(state_root: PathBuf) -> Self {
        if cow_state_feature::is_enabled(cow_state_feature::cow_state) {
            Self::ReadWrite(CowMemoryManagerCommon::<ReadWrite>::open(state_root))
        } else {
            Self::ReadWrite(CowMemoryManagerCommon::<ReadWrite>::open_fake())
        }
    }

    pub fn open_readwrite_statesync(state_root: PathBuf) -> Self {
        Self::ReadWrite(CowMemoryManagerCommon::<ReadWrite>::open(state_root))
    }

    pub fn open_readwrite_fake() -> Self {
        Self::ReadWrite(CowMemoryManagerCommon::<ReadWrite>::open_fake())
    }

    pub fn state_root(&self) -> PathBuf {
        match self {
            CowMemoryManagerImpl::ReadOnly(a) => a.state_root.clone(),
            CowMemoryManagerImpl::ReadWrite(a) => a.state_root.clone(),
        }
    }

    pub fn is_cow(state_root: &Path) -> bool {
        state_root.join("state_file").exists()
    }

    pub fn purge(state_root: &Path) {
        let state_file = state_root.join("state_file");
        std::fs::remove_file(&state_file).unwrap_or_else(|e| {
            panic!(
                "unable to delete state file {}: {}",
                state_file.display(),
                e
            )
        });

        let mapping_db = state_root.join("slot_db");
        std::fs::remove_dir_all(&mapping_db)
            .unwrap_or_else(|e| panic!("unable to delete slot_db {}: {}", mapping_db.display(), e));
    }
}

#[derive(Clone)]
pub struct CowMemoryManagerCommon<T> {
    state_root: PathBuf,
    meta: StateMeta,
    written_so_far: Arc<AtomicUsize>,
    fake: bool,
    _marker: PhantomData<T>,
}

impl CowMemoryManagerCommon<ReadOnly> {
    fn validate(state_file: File) -> StateMeta {
        unsafe {
            // map just the header portion
            let raw_fd = state_file.as_raw_fd();
            let header_base = mmap(ptr::null_mut(), PAGE_SIZE, PROT_READ, MAP_SHARED, raw_fd, 0);
            if header_base == MAP_FAILED {
                panic!("mmap failed: {}", Error::last_os_error());
            }
            let sm = std::ptr::read(header_base as *mut StateMeta);

            let magic = std::ptr::addr_of!(sm.magic);

            assert_eq!(magic.read_unaligned(), STATE_MAGIC);
            munmap(header_base, PAGE_SIZE);
            sm
        }
    }

    fn open_state_file(state_root: &Path) -> File {
        let state_file = state_root.join("state_file");
        assert!(
            state_file.exists(),
            "state_file should exists {:?}",
            state_file
        );

        OpenOptions::new()
            .read(true)
            .open(state_file)
            .expect("failed to open file")
    }

    pub fn open_fake() -> Self {
        Self {
            state_root: "NOT_USED".into(),
            meta: StateMeta::default(),
            written_so_far: Arc::new(AtomicUsize::new(INITIAL_WRITTEN_SIZE)),
            fake: true,
            _marker: PhantomData::<ReadOnly>,
        }
    }

    pub fn open(state_root: PathBuf) -> Self {
        let mut state_file = state_root.clone();
        state_file.push("state_file");

        if !state_file.exists() {
            return Self::open_fake();
        }

        let state_file = Self::open_state_file(&state_root);

        let mapping_db = state_root.join("slot_db");
        assert!(mapping_db.exists(), "mapping db path should exists");

        let meta = Self::validate(state_file);
        Self {
            state_root,
            meta,
            written_so_far: Arc::new(AtomicUsize::new(INITIAL_WRITTEN_SIZE)),
            fake: false,
            _marker: PhantomData::<ReadOnly>,
        }
    }
}

impl CowMemoryManagerCommon<ReadWrite> {
    fn validate(state_file: File) -> StateMeta {
        unsafe {
            // map just the header portion
            let raw_fd = state_file.as_raw_fd();
            let header_base = mmap(
                ptr::null_mut(),
                PAGE_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                raw_fd,
                0,
            );

            if header_base == MAP_FAILED {
                panic!("mmap failed: {}", Error::last_os_error());
            }

            let mut sm = std::ptr::read(header_base as *mut StateMeta);

            if sm.magic != STATE_MAGIC {
                sm.magic = STATE_MAGIC;
                sm.version = STATE_VERSION;

                sm.meta_offset = META_OFFSET;
                sm.meta_len = META_LEN;

                sm.globals_offset = GLOBALS_OFFSET;
                sm.globals_len = GLOBALS_LEN;

                sm.heap_offset = HEAP_OFFSET;
                sm.heap_len = HEAP_LEN;

                std::ptr::write(header_base as *mut StateMeta, sm);
            }

            munmap(header_base, PAGE_SIZE);
            sm
        }
    }

    fn open_state_file(state_root: &Path) -> File {
        let state_file = state_root.join("state_file");
        let file_exists = state_file.exists();

        if !file_exists {
            let parent = state_file.parent().unwrap();
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("failed to create path {:?}, {}", parent, e));
        }

        let file = OpenOptions::new()
            .create(!file_exists)
            .read(true)
            .write(true)
            .open(state_file.clone())
            .unwrap_or_else(|e| panic!("failed to open file {:?}, {}", state_file, e));

        if !file_exists {
            // Grow the file to `INITIAL_FILE_SIZE` initially
            file.set_len(INITIAL_FILE_SIZE as u64)
                .expect("failed to grow state file to 8GiB size");
        }
        file
    }

    pub fn open_fake() -> Self {
        Self {
            state_root: "NOT_USED".into(),
            meta: StateMeta::default(),
            written_so_far: Arc::new(AtomicUsize::new(INITIAL_WRITTEN_SIZE)),
            fake: true,
            _marker: PhantomData::<ReadWrite>,
        }
    }

    pub fn open(state_root: PathBuf) -> Self {
        let state_file = Self::open_state_file(&state_root);
        let mapping_db = state_root.join("slot_db");
        if !mapping_db.exists() {
            std::fs::create_dir_all(mapping_db.as_path()).expect("unable to create db directory");
        }

        let meta = Self::validate(state_file);
        Self {
            state_root,
            meta,
            written_so_far: Arc::new(AtomicUsize::new(INITIAL_WRITTEN_SIZE)),
            fake: false,
            _marker: PhantomData::<ReadWrite>,
        }
    }
}

impl std::fmt::Debug for CowMemoryManagerCommon<ReadOnly> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CowMemoryManager<ReadOnly>::state_root {:?}",
            self.state_root
        )
    }
}

impl std::fmt::Debug for CowMemoryManagerCommon<ReadWrite> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CowMemoryManager<ReadWrite>::state_root {:?}",
            self.state_root
        )
    }
}

fn get_slot_mgr_base_path(state_root: &Path) -> PathBuf {
    state_root.join("slot_db")
}

fn get_slot_mgr(state_root: &Path) -> Arc<SlotMgr> {
    // We open slot managers lazily intentionally.
    // This is efficient as for inactive canisters.
    // For active canisters/states they are opened once and remain open
    // until next point as those handles are created against the "tip"

    let mapping_db = get_slot_mgr_base_path(state_root);
    let smgr_list_read = SLOT_MGR_LIST.upgradable_read();
    match smgr_list_read.get(&mapping_db) {
        Some(smgr) => smgr.clone(),
        None => {
            let mut smgr_list_write = RwLockUpgradableReadGuard::upgrade(smgr_list_read);
            let smgr = Arc::new(SlotMgr::new(
                mapping_db.as_path(),
                MAX_ROUNDS,
                MAX_ROUNDS as u64 * HEAP_LEN as u64,
            ));

            smgr_list_write.insert(mapping_db.clone(), smgr.clone());
            smgr
        }
    }
}

impl<T: AccessPolicy> CowMemoryManagerCommon<T> {
    fn create_map(&self, state_file: File, round_to_use: Option<u64>) -> Result<MapInfo, CowError> {
        let magic = std::ptr::addr_of!(self.meta.magic);
        assert_eq!(unsafe { magic.read_unaligned() }, STATE_MAGIC);

        let slot_mgr = get_slot_mgr(&self.state_root);

        let current_mappings = match round_to_use {
            None => slot_mgr.get_current_round_mappings(),
            Some(round) => {
                // see if the round exists, else we will return
                // the current mappings
                let mut completed_rounds = slot_mgr.get_completed_rounds();
                completed_rounds.sort_unstable();
                let max_round = completed_rounds.pop();
                if max_round.is_some() && round <= max_round.unwrap() {
                    slot_mgr.get_mappings_for_round(round)?
                } else {
                    slot_mgr.get_current_round_mappings()
                }
            }
        };

        let state_raw_fd = state_file.as_raw_fd();

        let total_size =
            (self.meta.meta_len + self.meta.globals_len + self.meta.heap_len) * PAGE_SIZE;

        // embedders make only required amount of memory accessible
        // to canisters during execution along with wasmtime.
        // Setting PROT_NONE ensures rest remains inaccessible.
        let mapped_base = unsafe {
            mmap(
                ptr::null_mut(),
                total_size as usize,
                PROT_NONE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };

        if mapped_base == MAP_FAILED {
            panic!("mmap failed: {}", Error::last_os_error());
        }

        let mapped_base = mapped_base as *mut u8;

        // overlay individual pieces
        for SingleContigRange {
            logical_slot,
            physical_slot,
            map_len,
        } in current_mappings.into_iter()
        {
            unsafe {
                let where_to_map = mapped_base.add(logical_slot as usize * PAGE_SIZE);
                let what_to_map = (physical_slot + self.meta.meta_len as u64) * PAGE_SIZE as u64;

                let overlay_mem = mmap(
                    where_to_map as *mut c_void,
                    map_len as usize * PAGE_SIZE,
                    PROT_NONE,
                    MAP_PRIVATE | MAP_NORESERVE | MAP_FIXED,
                    state_raw_fd,
                    what_to_map as i64,
                );

                if overlay_mem == MAP_FAILED {
                    panic!("mmap failed: {}", Error::last_os_error());
                }
                assert_eq!(overlay_mem as u64, where_to_map as u64);
            }
        }

        Ok(MapInfo {
            mapped_base: mapped_base as u64,
            mapped_len: total_size,
            file: state_file,
            state_root: self.state_root.clone(),
            current_mappings,
            written_so_far: self.written_so_far.clone(),
        })
    }

    fn get_map_for_snapshot(
        &self,
        file: File,
        round_to_use: u64,
    ) -> Result<MappedStateImpl, CowError> {
        let map_info = self.create_map(file, Some(round_to_use))?;

        let internal = MappedStateCommon::<ReadOnly> {
            meta: self.meta,
            map_info,
            _marker: PhantomData::<ReadOnly>,
        };

        Ok(MappedStateImpl {
            mapped_state: MappedStates::ReadOnly(internal),
        })
    }
}

impl CowMemoryManager for CowMemoryManagerCommon<ReadOnly> {
    fn get_map_for_snapshot(&self, round_to_use: u64) -> Result<MappedStateImpl, CowError> {
        let file = Self::open_state_file(&self.state_root);
        self.get_map_for_snapshot(file, round_to_use)
    }

    fn get_map(&self) -> MappedStateImpl {
        let file = Self::open_state_file(&self.state_root);
        let map_info = self.create_map(file, None).unwrap();

        let internal = MappedStateCommon::<ReadOnly> {
            meta: self.meta,
            map_info,
            _marker: PhantomData::<ReadOnly>,
        };

        MappedStateImpl {
            mapped_state: MappedStates::ReadOnly(internal),
        }
    }

    fn is_valid(&self) -> bool {
        !self.fake
    }

    fn create_snapshot(&self, _end_round: u64) {
        unimplemented!("create_snapshot() is not supported");
    }

    fn checkpoint(&self) {
        unimplemented!("checkpoint() is not supported");
    }

    fn upgrade(&self) {
        unimplemented!("upgrade() is not supported");
    }

    fn remove_states_below(&self, _round: u64) {
        panic!("remove_states_below() is not supported");
    }
}

impl CowMemoryManager for CowMemoryManagerCommon<ReadWrite> {
    fn get_map(&self) -> MappedStateImpl {
        let file = Self::open_state_file(&self.state_root);
        let map_info = self.create_map(file, None).unwrap();

        let internal = MappedStateCommon::<ReadWrite> {
            meta: self.meta,
            map_info,
            _marker: PhantomData::<ReadWrite>,
        };

        MappedStateImpl {
            mapped_state: MappedStates::ReadWrite(internal),
        }
    }

    fn get_map_for_snapshot(&self, round_to_use: u64) -> Result<MappedStateImpl, CowError> {
        let file = Self::open_state_file(&self.state_root);
        self.get_map_for_snapshot(file, round_to_use)
    }

    fn create_snapshot(&self, round: u64) {
        if !self.is_valid() {
            return;
        }

        let slot_mgr = get_slot_mgr(&self.state_root);
        slot_mgr.end_round(round);
    }

    fn checkpoint(&self) {
        if !self.is_valid() {
            return;
        }

        let file = Self::open_state_file(&self.state_root);
        file.sync_data()
            .unwrap_or_else(|e| panic!("flush to state_file failed {}", e));

        let slot_mgr = get_slot_mgr(&self.state_root);
        slot_mgr.checkpoint();

        drop(slot_mgr);

        let base_path = &get_slot_mgr_base_path(&self.state_root);
        let mut smgr_list_write = SLOT_MGR_LIST.write();
        if let Some(smgr) = smgr_list_write.get(base_path) {
            if Arc::strong_count(smgr) == 1 {
                // remove if this is the last active reference
                smgr_list_write.remove(base_path);
            }
        }

        // Reset the accounting to initial value as we are begining afresh
        // and start accounting for all new writes
        self.written_so_far
            .store(INITIAL_WRITTEN_SIZE, Ordering::Relaxed);
    }

    fn remove_states_below(&self, round: u64) {
        if !self.is_valid() {
            return;
        }

        let slot_mgr = get_slot_mgr(&self.state_root);
        slot_mgr.remove_rounds_below(round);
    }

    fn upgrade(&self) {
        if cow_state_feature::is_enabled(cow_state_feature::cow_state) {
            self.get_map().clear();
        }
    }

    fn is_valid(&self) -> bool {
        !self.fake
    }
}
impl fmt::Debug for MappedStateImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let is_readonly = match self.mapped_state {
            MappedStates::ReadOnly(_) => true,
            MappedStates::ReadWrite(_) => false,
        };
        write!(
            f,
            "is_readonly {} base {:?}",
            is_readonly,
            self.get_heap_base()
        )
    }
}

#[cfg(test)]
const INITIAL_WRITTEN_SIZE: usize = 8 * KB as usize;
#[cfg(test)]
const INITIAL_FILE_SIZE: usize = 20 * KB as usize;
#[cfg(test)]
const GROW_THRESHOLD: usize = 12 * KB as usize;
#[cfg(test)]
const GROW_SIZE: usize = 12 * KB as usize;
#[test]
fn cow_test_file_grow() {
    cow_state_feature::enable(cow_state_feature::cow_state);
    use tempfile::tempdir;
    let random_bytes: Vec<u8> = (0..PAGE_SIZE).map(|_| rand::random::<u8>()).collect();

    let test_dir = tempdir().expect("Unable to create temp directory");
    let mut p = test_dir.path().to_path_buf();
    let cow_mem_mgr = CowMemoryManagerImpl::open_readwrite(test_dir.path().into());
    p.push("state_file");

    let f = File::open(p).unwrap();

    let orig_len = f.metadata().unwrap().len() as usize;

    // write 4K. This should grow the file by atleast GROW_SIZE as we would
    // have crossed the threshold, 8k + 4k + 4k > 12k
    let mapped_state = cow_mem_mgr.get_map();
    mapped_state.copy_to_heap(0, &random_bytes);
    mapped_state.soft_commit(&[0]);
    let len = f.metadata().unwrap().len() as usize;
    assert!(len >= orig_len + GROW_SIZE);
    let orig_len = len;

    // write again, this should not increase the length
    let mapped_state = cow_mem_mgr.get_map();
    mapped_state.copy_to_heap(4096, &random_bytes);
    mapped_state.soft_commit(&[1]);

    let len = f.metadata().unwrap().len() as usize;
    assert_eq!(len, orig_len);

    // write again, this will trigger grow
    let mapped_state = cow_mem_mgr.get_map();
    mapped_state.copy_to_heap(2 * 4096, &random_bytes);
    mapped_state.soft_commit(&[2]);
    let len = f.metadata().unwrap().len() as usize;
    assert!(len >= orig_len + GROW_SIZE);
    let orig_len = len;

    // Checkpoint so we can use reuse parts of the file
    cow_mem_mgr.create_snapshot(42);
    cow_mem_mgr.checkpoint();

    let mapped_state = cow_mem_mgr.get_map();
    for i in 0..3 {
        mapped_state.copy_to_heap(i * 4096, &random_bytes);
    }
    mapped_state.soft_commit(&[0, 1, 2]);
    let len = f.metadata().unwrap().len() as usize;
    assert_eq!(len, orig_len);

    // Create additional snapshot to account for multiple writes to
    // same heap regions. This should trigger grow
    cow_mem_mgr.create_snapshot(43);

    let mapped_state = cow_mem_mgr.get_map();
    for i in 0..3 {
        mapped_state.copy_to_heap(i * 4096, &random_bytes);
    }
    mapped_state.soft_commit(&[0, 1, 2]);
    let len = f.metadata().unwrap().len() as usize;
    assert!(len >= orig_len + GROW_SIZE);
}

#[cfg(test)]
const HEAP_LEN: usize = 3;
#[cfg(test)]
const MAX_ROUNDS: u32 = 5;

#[test]
fn cow_test_write_max_rounds() {
    // This test verifies that we can write full heaps upto max rounds
    // and can retrieve them. This validates various sizing
    cow_state_feature::enable(cow_state_feature::cow_state);
    use tempfile::tempdir;

    let test_dir = tempdir().expect("Unable to create temp directory");
    let cow_mem_mgr = CowMemoryManagerImpl::open_readwrite(test_dir.path().into());

    // Write full heaps for max_rounds
    for i in 1..MAX_ROUNDS + 1 {
        let random_bytes: Vec<u8> = (0..(HEAP_LEN * PAGE_SIZE)).map(|_| i as u8).collect();
        let mapped_state = cow_mem_mgr.get_map();
        let pages = mapped_state.copy_to_heap(0, &random_bytes);
        mapped_state.soft_commit(&pages);
        cow_mem_mgr.create_snapshot(i as u64);
    }

    // Verifiy that all are persisted correctly and can be retrieved
    for i in 1..MAX_ROUNDS + 1 {
        let random_bytes: Vec<u8> = (0..(HEAP_LEN * PAGE_SIZE)).map(|_| i as u8).collect();
        let mapped_state = cow_mem_mgr.get_map_for_snapshot(i as u64).unwrap();
        let data = mapped_state.copy_from_heap(0, random_bytes.len() as u64);

        assert_eq!(data, random_bytes.as_slice());
    }

    cow_mem_mgr.checkpoint();
    cow_mem_mgr.remove_states_below(MAX_ROUNDS as u64);

    // Write max_rounds - 1 to make sure that those can be persisted correctly
    for i in 1..MAX_ROUNDS {
        let random_bytes: Vec<u8> = (0..(HEAP_LEN * PAGE_SIZE))
            .map(|_| (MAX_ROUNDS + i) as u8)
            .collect();
        let mapped_state = cow_mem_mgr.get_map();
        let pages = mapped_state.copy_to_heap(0, &random_bytes);
        mapped_state.soft_commit(&pages);
        cow_mem_mgr.create_snapshot((MAX_ROUNDS + i) as u64);
    }

    // Drop required only to keep lmdb on mac happy
    drop(cow_mem_mgr);

    // Verify all new modifications and one old modification is stored correctly
    let cow_mem_mgr = CowMemoryManagerImpl::open_readonly(test_dir.path().into());
    for i in 1..MAX_ROUNDS {
        let random_bytes: Vec<u8> = (0..(HEAP_LEN * PAGE_SIZE))
            .map(|_| (MAX_ROUNDS + i) as u8)
            .collect();
        let mapped_state = cow_mem_mgr
            .get_map_for_snapshot((MAX_ROUNDS + i) as u64)
            .unwrap();
        let data = mapped_state.copy_from_heap(0, random_bytes.len() as u64);

        assert_eq!(data, random_bytes.as_slice());
    }

    let random_bytes: Vec<u8> = (0..(HEAP_LEN * PAGE_SIZE))
        .map(|_| MAX_ROUNDS as u8)
        .collect();
    let mapped_state = cow_mem_mgr.get_map_for_snapshot(MAX_ROUNDS as u64).unwrap();
    let data = mapped_state.copy_from_heap(0, random_bytes.len() as u64);

    assert_eq!(data, random_bytes.as_slice());
}
