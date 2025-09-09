#![no_main]
use ic_replicated_state::page_map::storage::tests::{Instruction, write_overlays_and_verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|instructions: Vec<Instruction>| {
    if !instructions.is_empty() {
        // WriteOverlay can be empty
        let filter_instructions = instructions
            .into_iter()
            .filter_map(|instruction| match instruction {
                Instruction::WriteOverlay(ref offset) => {
                    if offset.is_empty() {
                        return None;
                    }
                    Some(Instruction::WriteOverlay(
                        // [TODO]: Tempfix for 3 digit encoding
                        offset.iter().map(|i| i % 999_u64).collect(),
                    ))
                }
                Instruction::Merge { is_downgrade, .. } => Some(Instruction::Merge {
                    assert_files_merged: None,
                    is_downgrade,
                }),
            })
            .collect::<Vec<_>>();

        write_overlays_and_verify(filter_instructions);
    }
});
