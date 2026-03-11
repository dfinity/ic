//! Handles the lowering of WAT AST to structural WebAssembly text format.

use std::collections::HashMap;

use crate::wat_canister::fn_builder::{FnCall, WAIT_SCRATCHPAD_START};

/// Mutable internal state for lowering Wasm AST calls to strings
pub(crate) struct RenderState<'a> {
    pub(crate) next_loop_id: usize,
    pub(crate) memory: &'a mut HashMap<Vec<u8>, i32>,
    pub(crate) memory_offset: &'a mut i32,
    pub(crate) instructions: Vec<String>,
}

impl<'a> RenderState<'a> {
    /// Count the exact number of Nested/Successive Loops required to allocate local descriptors.
    pub(crate) fn count_loops(calls: &[FnCall]) -> usize {
        let mut count = 0;
        for call in calls {
            if let FnCall::Loop(_, inner) = call {
                count += 1 + Self::count_loops(inner);
            }
        }
        count
    }

    fn get_memory_offset(&mut self, message: &[u8]) -> i32 {
        if let Some(&offset) = self.memory.get(message) {
            offset
        } else {
            let offset = *self.memory_offset;
            let message_size = message.len() as i32;

            if offset + message_size > WAIT_SCRATCHPAD_START {
                panic!(
                    "Memory limit exceeded: allocation of size {} at offset {} overlaps with the reserved wait() scratchpad (which begins at {}).\n\
                    Current implementation supports only 1 page of memory (64KiB) and reserves the end for CPU burn loops.",
                    message_size, offset, WAIT_SCRATCHPAD_START
                );
            }

            self.memory.insert(message.to_vec(), offset);
            *self.memory_offset += message_size;

            offset
        }
    }

    pub(crate) fn process_calls(&mut self, calls: &[FnCall], indent: &str) {
        for call in calls {
            match call {
                FnCall::StableGrow(new_pages) => self.instructions.push(format!(
                    "(drop (call $ic0_stable_grow (i32.const {new_pages})))"
                )),
                FnCall::StableRead(dst, offset, size) => self.instructions.push(format!(
                    "(call $ic0_stable_read (i32.const {dst}) (i32.const {offset}) (i32.const {size}))"
                )),
                FnCall::GlobalTimerSet(timestamp) => self.instructions.push(format!(
                    "(drop (call $ic0_global_timer_set (i64.const {timestamp})))"
                )),
                FnCall::DebugPrint(message) => {
                    let off = self.get_memory_offset(message);
                    let len = message.len() as i32;
                    self.instructions.push(format!(
                        "(call $ic0_debug_print (i32.const {off}) (i32.const {len}))"
                    ));
                }
                FnCall::Trap(message) => {
                    let off = self.get_memory_offset(message);
                    let len = message.len() as i32;
                    self.instructions.push(format!(
                        "(call $ic0_trap (i32.const {off}) (i32.const {len}))"
                    ));
                }
                FnCall::Unreachable => self.instructions.push("(unreachable)".to_string()),
                FnCall::DivByZero => self
                    .instructions
                    .push("(i32.div_s (i32.const 1) (i32.const 0))".to_string()),
                FnCall::Wait(instructions) => self
                    .instructions
                    .push(format!("(call $_wait (i64.const {instructions}))")),
                FnCall::Loop(count, inner_calls) => {
                    let id = self.next_loop_id;
                    self.next_loop_id += 1;

                    self.instructions.push(format!(
                        "(local.set $loop_counter_{id} (i32.const {count}))"
                    ));
                    self.instructions.push(format!("(loop $loop_label_{id}"));

                    let inner_indent = format!("{}    ", indent);
                    self.instructions.push(format!(
                        "{inner_indent}(if (i32.gt_u (local.get $loop_counter_{id}) (i32.const 0))"
                    ));
                    self.instructions.push(format!("{inner_indent}    (then"));

                    // Render inner code logic
                    self.process_calls(inner_calls, &format!("{inner_indent}        "));

                    // Step control block
                    self.instructions.push(format!("{inner_indent}        (local.set $loop_counter_{id} (i32.sub (local.get $loop_counter_{id}) (i32.const 1)))"));
                    self.instructions
                        .push(format!("{inner_indent}        (br $loop_label_{id})"));

                    // Close block layout
                    self.instructions.push(format!("{inner_indent}    )"));
                    self.instructions.push(format!("{inner_indent})"));
                    self.instructions.push(format!("{indent})"));
                }
            }
        }
    }
}

/// WebAssembly text format requires byte escapes to be specifically formatted
/// as `\hh` where `h` is a hex character. Rust's `.escape_ascii()` creates
/// `\xhh` which causes strict `wat` parsers to panic at construction.
pub(crate) fn format_wasm_string(data: &[u8]) -> String {
    use std::fmt::Write;

    let mut s = String::with_capacity(data.len() * 3);
    for &b in data {
        if b.is_ascii_graphic() && b != b'\\' && b != b'"' || b == b' ' {
            s.push(b as char);
        } else {
            let _ = write!(&mut s, "\\{:02x}", b);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_wasm_string() {
        assert_eq!(format_wasm_string(b"hello"), "hello");
        assert_eq!(format_wasm_string(b"hi there"), "hi there");

        // Escaping boundaries
        assert_eq!(format_wasm_string(b"\"quotes\""), "\\22quotes\\22");
        assert_eq!(
            format_wasm_string(b"\\backslashes\\"),
            "\\5cbackslashes\\5c"
        );

        // Non-printable control characters
        assert_eq!(format_wasm_string(&[0x00, 0x0A, 0x0D]), "\\00\\0a\\0d");

        // High-bit byte (non-ASCII)
        assert_eq!(format_wasm_string(&[0xC0, 0xFF, 0xFE]), "\\c0\\ff\\fe");

        // Mixed content
        assert_eq!(
            format_wasm_string(b"hello \n world \x01!"),
            "hello \\0a world \\01!"
        );
    }
}
