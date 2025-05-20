//! Logic for lazily loading canister memory as it is accessed.
//!
//! API is meant to be called by the system API which is responsible for
//! validating that the accesses are in bounds.

use std::ops::Range;
use std::os::raw::c_void;

use ic_replicated_state::page_map::{MemoryInstructions, MemoryMapOrData};
use ic_replicated_state::PageMap;
use ic_sys::{PageIndex, PAGE_SIZE};
use ic_types::NumOsPages;
use nix::sys::mman::{mmap, mprotect, MapFlags, ProtFlags};
use wasmtime_environ::WASM32_MAX_SIZE;

// The upper bound on the number of pages that are memory mapped from the
// checkpoint file per signal handler call. Higher value gives higher
// throughput in memory intensive workloads, but may regress performance
// in other workloads because it increases work per signal handler call.
const MAX_PAGES_TO_MAP: usize = 128;

const NO_ACCESS: u8 = 0;
const WRITE_ACCESS: u8 = 1;
const READ_ONLY_ACCESS: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AccessType {
    Read,
    Write,
}

fn range_size_in_bytes(range: &Range<PageIndex>) -> usize {
    (range.end.get() - range.start.get()) as usize * PAGE_SIZE
}

fn range_from_count(page: PageIndex, count: NumOsPages) -> Range<PageIndex> {
    PageIndex::new(page.get().saturating_sub(count.get()))..PageIndex::new(page.get() + count.get())
}

// Returns the largest range around the faulting page such that all pages there have
// not been marked yet.
fn restrict_range_to_unmarked(
    bytemap: &[u8],
    faulting_page: PageIndex,
    range: Range<PageIndex>,
    access_type: AccessType,
) -> Range<PageIndex> {
    debug_assert!(
        range.contains(&faulting_page),
        "Error checking page:{faulting_page} ∈ range:{range:?}"
    );
    let default = match access_type {
        AccessType::Read => NO_ACCESS,
        AccessType::Write => READ_ONLY_ACCESS,
    };
    let target = match access_type {
        AccessType::Read => NO_ACCESS,
        AccessType::Write => READ_ONLY_ACCESS,
    };
    // TODO: Need to add back?
    // let range = range_intersection(&range, &self.page_range());
    let old_start = range.start.get();
    let mut start = faulting_page.get();
    while start > old_start {
        if bytemap.get(start as usize - 1).unwrap_or(&default) != &target {
            break;
        }
        start -= 1;
    }
    let old_end = range.end.get();
    let mut end = faulting_page.get();
    while end < old_end {
        if bytemap.get(end as usize).unwrap_or(&default) != &target {
            break;
        }
        end += 1;
    }

    PageIndex::new(start)..PageIndex::new(end)
}

// Returns the range of pages that are predicted to be marked in the future
// based on the marked pages before the start of the given range or after the end.
fn restrict_range_to_predicted(
    bytemap: &[u8],
    faulting_page: PageIndex,
    range: Range<PageIndex>,
    access_type: AccessType,
) -> Range<PageIndex> {
    debug_assert!(
        range.contains(&faulting_page),
        "Error checking page:{faulting_page} ∈ range:{range:?}"
    );
    // TODO: Need to add back?
    // let range = range_intersection(&range, &self.page_range());
    if range.is_empty() {
        return range;
    }

    let matches_access = match access_type {
        AccessType::Read => |i| i != &NO_ACCESS,
        AccessType::Write => |i| i == &WRITE_ACCESS,
    };

    let page = faulting_page.get();
    let start = range.start.get();
    let end = range.end.get();

    let mut bwd_predicted_count = 0;
    while page - bwd_predicted_count > start {
        if matches_access(
            bytemap
                .get((page + bwd_predicted_count + 1) as usize)
                .unwrap_or(&NO_ACCESS),
        ) {
            break;
        }
        bwd_predicted_count += 1;
    }

    let mut fwd_predicted_count = 1;
    while fwd_predicted_count < page && page + fwd_predicted_count < end {
        if matches_access(
            bytemap
                .get((page - fwd_predicted_count) as usize)
                .unwrap_or(&NO_ACCESS),
        ) {
            break;
        }
        fwd_predicted_count += 1;
    }

    PageIndex::new(page - bwd_predicted_count)..PageIndex::new(page + fwd_predicted_count)
}

pub(crate) struct MemoryLoader {
    /// The state of canister memory before the execution of this message.
    page_map: PageMap,
    /// The base address of the Wasm instance's memory.
    base_addr: usize,
}

impl MemoryLoader {
    pub fn new(page_map: PageMap, base_addr: usize) -> Self {
        // println!("Setting up memory at base address {:x}", base_addr);
        let result = Self {
            page_map,
            base_addr,
        };
        result.initial_setup();
        result
    }

    fn page_start_addr(&self, page: PageIndex) -> *mut c_void {
        (self.base_addr + PAGE_SIZE * page.get() as usize) as *mut c_void
    }

    fn initial_setup(&self) {
        // println!("mprotecting up to {WASM32_MAX_SIZE:x}");
        unsafe {
            mprotect(
                self.base_addr as *mut c_void,
                WASM32_MAX_SIZE as usize,
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            )
        }
        .unwrap();
        // std::thread::sleep(std::time::Duration::MAX);
        let instructions = self.page_map.get_base_memory_instructions();
        self.apply_instructions(instructions);
    }

    /// Assumes that the page index is valid for the bytemap and memory region.
    pub(crate) fn load_page(
        &self,
        bytemap: &mut [u8],
        faulting_page: PageIndex,
        access_type: AccessType,
    ) {
        if access_type == AccessType::Write
            && bytemap[faulting_page.get() as usize] == READ_ONLY_ACCESS
        {
            let prefetch_range =
                range_from_count(faulting_page, NumOsPages::new(MAX_PAGES_TO_MAP as u64));
            let max_prefetch_range = restrict_range_to_unmarked(
                bytemap,
                faulting_page,
                prefetch_range,
                AccessType::Write,
            );
            let min_prefetch_range = restrict_range_to_predicted(
                bytemap,
                faulting_page,
                max_prefetch_range.clone(),
                AccessType::Write,
            );
            // let updated_range = self.load_range(min_prefetch_range, max_prefetch_range);
            for i in min_prefetch_range.start.get() as usize..min_prefetch_range.end.get() as usize
            {
                bytemap[i] = WRITE_ACCESS;
            }
        } else {
            let prefetch_range =
                range_from_count(faulting_page, NumOsPages::new(MAX_PAGES_TO_MAP as u64));
            let max_prefetch_range = restrict_range_to_unmarked(
                bytemap,
                faulting_page,
                prefetch_range,
                AccessType::Read,
            );
            let min_prefetch_range = restrict_range_to_predicted(
                bytemap,
                faulting_page,
                max_prefetch_range.clone(),
                access_type,
            );
            let updated_range = self.load_range(min_prefetch_range, max_prefetch_range);
            let new_value = match access_type {
                AccessType::Read => READ_ONLY_ACCESS,
                AccessType::Write => WRITE_ACCESS,
            };
            for i in updated_range {
                bytemap[i as usize] = new_value;
            }
        }
    }

    fn load_range(&self, min_range: Range<PageIndex>, max_range: Range<PageIndex>) -> Range<u64> {
        let instructions = self.page_map.get_memory_instructions(min_range, max_range);
        let result = instructions.range.start.get()..instructions.range.end.get();
        self.apply_instructions(instructions);
        result
    }

    fn apply_instructions(&self, instructions: MemoryInstructions) {
        for (range, memory_or_data) in instructions.instructions {
            match memory_or_data {
                MemoryMapOrData::MemoryMap(file_descriptor, offset) => {
                    let _addr = unsafe {
                        mmap(
                            self.page_start_addr(range.start),
                            range_size_in_bytes(&range),
                            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                            MapFlags::MAP_PRIVATE | MapFlags::MAP_FIXED,
                            file_descriptor.fd,
                            offset as i64,
                        )
                    }
                    .unwrap();
                }
                MemoryMapOrData::Data(data) => unsafe {
                    std::ptr::copy_nonoverlapping(
                        data.as_ptr() as *const libc::c_void,
                        self.page_start_addr(range.start),
                        range_size_in_bytes(&range),
                    )
                },
            }
        }
    }
}
