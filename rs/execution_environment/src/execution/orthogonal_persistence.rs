/// ! True orthogonal persistence support
///
/// Retain the Wasm memory on upgrade, with only one exception:
/// * The new Wasm data segments must be loaded into the old memory.
///   This data represents static declarations of the new Wasm binary.
///
/// Safety assertion:
/// * The data segments reside in a reserved memory space between 2MB and 4MB
///   that must not be used by the persistent memory of the runtime system.
///
use core::cmp::min;
use std::sync::Arc;

use ic_embedders::wasm_utils::wasm_transform::{DataSegmentKind, Module};
use ic_replicated_state::{canister_state::execution_state::WasmBinary, Memory};
use ic_sys::{PageIndex, PAGE_SIZE};
use wasmparser::Operator;

struct DataSegment {
    offset: usize,
    length: usize,
}

impl DataSegment {
    fn new(offset: usize, length: usize) -> Self {
        assert!(offset >= DATA_SEGMENT_LOWER_LIMIT && offset + length <= DATA_SEGMENT_UPPER_LIMIT);
        DataSegment { offset, length }
    }

    fn chunk_in_pages(&self) -> Vec<PageChunk> {
        let mut result = vec![];
        let mut current = self.offset;
        let end = self.offset + self.length;
        while current < end {
            let page_index = PageIndex::new((current / PAGE_SIZE) as u64);
            let offset = current % PAGE_SIZE;
            let length = min(PAGE_SIZE - offset, end - current);
            let page_chunk = PageChunk {
                page_index,
                offset,
                length,
            };
            result.push(page_chunk);
            current += length;
        }
        result
    }
}

struct PageChunk {
    page_index: PageIndex,
    offset: usize,
    length: usize,
}

const MB: usize = 1024 * 1024;
const DATA_SEGMENT_LOWER_LIMIT: usize = 2 * MB;
const DATA_SEGMENT_UPPER_LIMIT: usize = 8 * MB;

// TODO: Possibly simplify by overwriting the entire reserved data segment memory range (2MB, 4MB)
// and only checking the data segment locations.

/// Orthogonal persistence helper
pub struct OrthogonalPersistence {
    wasm_binary: Arc<WasmBinary>,
    combined_memory: Memory,
    new_memory: Memory,
}

impl OrthogonalPersistence {
    /// Prepare new canister memory on upgrade by retaining the old memory state except the new Wasm data segments.
    pub fn upgrade_memory(
        wasm_binary: Arc<WasmBinary>,
        old_memory: Memory,
        new_memory: Memory,
    ) -> Memory {
        let combined_memory = Memory::new(old_memory.page_map.clone(), old_memory.size);
        let mut persistence = OrthogonalPersistence {
            wasm_binary,
            combined_memory,
            new_memory,
        };
        persistence.upgrade_static_data();
        persistence.combined_memory
    }

    fn upgrade_static_data(&mut self) {
        for data_segment in &self.parse_data_segments() {
            self.write_data_segment(data_segment);
        }
    }

    fn write_data_segment(&mut self, data_segment: &DataSegment) {
        for page_chunk in &data_segment.chunk_in_pages() {
            self.write_page_chunk(page_chunk);
        }
    }

    fn write_page_chunk(&mut self, page_chunk: &PageChunk) {
        let page_index = page_chunk.page_index;
        let current_page = self.combined_memory.page_map.get_page(page_index);
        let new_page = self.new_memory.page_map.get_page(page_index);
        let mut combined_page = *current_page;
        let start = page_chunk.offset;
        let end = start + page_chunk.length;
        combined_page[start..end].copy_from_slice(&new_page[start..end]);
        self.combined_memory
            .page_map
            .update(&[(page_index, &combined_page)]);
    }

    fn parse_data_segments(&self) -> Vec<DataSegment> {
        let wasm = self.wasm_binary.as_ref().binary.as_slice();
        let module = Module::parse(wasm, false).unwrap();
        let mut result = vec![];
        for data_segment in module.data {
            match data_segment.kind {
                DataSegmentKind::Active {
                    memory_index: _,
                    offset_expr,
                } => {
                    let length = data_segment.data.len();
                    let offset = match offset_expr {
                        Operator::I32Const { value } => value as usize,
                        Operator::I64Const { value } => value as usize,
                        _ => unimplemented!(),
                    };
                    let data_segment = DataSegment::new(offset, length);
                    result.push(data_segment);
                }
                DataSegmentKind::Passive => {}
            };
        }
        result
    }
}
