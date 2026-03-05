use std::collections::HashMap;
use strum_macros::EnumIter;

#[cfg(test)]
mod tests;

const STEP: &str = "    ";
const INDENT: &str = "\n            ";

const MEMORY_FILL_MAX: i32 = 100;

/// The memory index region used by the Wasm `_wait` loop to simulate CPU work.
const WAIT_SCRATCHPAD_START: i32 = 65_000;

/// The memory offset where user-injected strings begin allocating.
const MEMORY_OFFSET_START: i32 = 1_000;

/// We assert that the user allocations (`MEMORY_OFFSET_START`) start early,
/// and the `_wait` scratchpad is parked at the extreme end of the memory page.
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(MEMORY_OFFSET_START < WAIT_SCRATCHPAD_START);

/// The maximum 1-page bounds of WebAssembly memory (64 KiB).

#[derive(Clone)]
enum FnCall {
    StableGrow(i32),
    StableRead(i32, i32, i32),
    GlobalTimerSet(i64),
    DebugPrint(Vec<u8>),
    Trap(Vec<u8>),
    Wait(i64),
    Loop(u32, Vec<FnCall>),
}

/// Create a new WAT function code builder.
pub fn wat_fn() -> WatFnCode {
    WatFnCode::new()
}

/// WAT function code builder, allows to chain function calls.
#[derive(Clone)]
pub struct WatFnCode {
    calls: Vec<FnCall>,
}

impl WatFnCode {
    /// Create the content of a WAT function.
    pub fn new() -> Self {
        Self { calls: vec![] }
    }

    /// Call the `ic0.stable_grow` function.
    pub fn stable_grow(mut self, additional_pages: i32) -> Self {
        self.calls.push(FnCall::StableGrow(additional_pages));
        self
    }

    /// Call the `ic0.stable_read` function.
    pub fn stable_read(mut self, dst: i32, offset: i32, size: i32) -> Self {
        self.calls.push(FnCall::StableRead(dst, offset, size));
        self
    }

    /// Call the `ic0.global_timer_set` function.
    ///
    /// The name `api_global_timer_set` is similar to universal canister one.
    pub fn api_global_timer_set(mut self, timestamp: i64) -> Self {
        self.calls.push(FnCall::GlobalTimerSet(timestamp));
        self
    }

    /// Call the `ic0.debug_print` function.
    pub fn debug_print(mut self, message: &[u8]) -> Self {
        self.calls.push(FnCall::DebugPrint(message.to_vec()));
        self
    }

    /// Call the `ic0.trap` function.
    pub fn trap_with_blob(mut self, message: &[u8]) -> Self {
        self.calls.push(FnCall::Trap(message.to_vec()));
        self
    }

    /// Call the `ic0.trap` function.
    pub fn trap(self) -> Self {
        self.trap_with_blob(&[])
    }

    /// Wait for a given number of instructions.
    ///
    /// **WARNING**: This instruction simulates CPU cycles by executing `memory.fill` operations.
    /// It reserves and will completely clobber the WebAssembly memory addresses
    /// from `65,000` to `65,100`.
    pub fn wait(mut self, instructions: i64) -> Self {
        self.calls.push(FnCall::Wait(instructions));
        self
    }

    /// Loop a block of operations `count` times.
    ///
    /// This uses native WebAssembly `(loop)` instructions internally, meaning
    /// `count` can be extremely high (e.g. `100_000`) without inflating
    /// the generated Wasm binary size.
    pub fn repeat(mut self, count: u32, block: WatFnCode) -> Self {
        self.calls.push(FnCall::Loop(count, block.calls));
        self
    }
}

impl Default for WatFnCode {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, PartialEq, Debug, EnumIter)]
enum Method {
    Start,
    Init,
    PreUpgrade,
    PostUpgrade,
    InspectMessage,
    Heartbeat,
    GlobalTimer,
    Update,
    Query,
    CompositeQuery,
}

#[derive(Clone)]
struct WatFunc {
    method: Method,
    name: String,
    code: WatFnCode,
}

impl WatFunc {
    /// Emit the declaration prefix for this Wasm function.
    fn export_declaration(&self) -> String {
        match self.method {
            Method::Start => format!(r#"start $start){INDENT}(func $start"#),
            Method::Init => r#"func $init (export "canister_init")"#.to_string(),
            Method::PreUpgrade => {
                r#"func $pre_upgrade (export "canister_pre_upgrade")"#.to_string()
            }
            Method::PostUpgrade => {
                r#"func $post_upgrade (export "canister_post_upgrade")"#.to_string()
            }
            Method::InspectMessage => {
                r#"func $inspect_message (export "canister_inspect_message")"#.to_string()
            }
            Method::Heartbeat => r#"func $heartbeat (export "canister_heartbeat")"#.to_string(),
            Method::GlobalTimer => {
                r#"func $global_timer (export "canister_global_timer")"#.to_string()
            }
            Method::Update => format!(
                r#"func ${} (export "canister_update {}")"#,
                self.name, self.name
            ),
            Method::Query => format!(
                r#"func ${} (export "canister_query {}")"#,
                self.name, self.name
            ),
            Method::CompositeQuery => format!(
                r#"func ${} (export "canister_composite_query {}")"#,
                self.name, self.name
            ),
        }
    }
}

/// Create a new WAT canister builder.
pub fn wat_canister() -> WatCanisterBuilder {
    WatCanisterBuilder::new()
}

/// The WAT canister builder creates a WAT canister with multiple functions of varying content.
///
/// A WAT canister allows for modifiable behavior within tests.
/// It is similar to the `universal_canister` but addresses specific cases the UC can't.
/// It modifies methods that occur right after start and before any update call,
/// covering `init()`, `start()`, and `post_upgrade()` methods.
#[derive(Clone)]
pub struct WatCanisterBuilder {
    functions: Vec<WatFunc>,
    memory_offset: i32,
    memory: HashMap<Vec<u8>, i32>,
}

impl WatCanisterBuilder {
    /// Create a builder for a new WAT canister.
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            memory_offset: MEMORY_OFFSET_START,
            memory: HashMap::new(),
        }
    }

    /// Add `start` function to the WAT canister.
    pub fn start(self, code: WatFnCode) -> Self {
        self.process_method(Method::Start, "start", code)
    }

    /// Add `canister_init` exported function to the WAT canister.
    pub fn init(self, code: WatFnCode) -> Self {
        self.process_method(Method::Init, "init", code)
    }

    /// Add `canister_pre_upgrade` exported function to the WAT canister.
    pub fn pre_upgrade(self, code: WatFnCode) -> Self {
        self.process_method(Method::PreUpgrade, "pre_upgrade", code)
    }

    /// Add `canister_post_upgrade` exported function to the WAT canister.
    pub fn post_upgrade(self, code: WatFnCode) -> Self {
        self.process_method(Method::PostUpgrade, "post_upgrade", code)
    }

    /// Add `canister_inspect_message` exported function to the WAT canister.
    pub fn inspect_message(self, code: WatFnCode) -> Self {
        self.process_method(Method::InspectMessage, "inspect_message", code)
    }

    /// Add `canister_heartbeat` exported function to the WAT canister.
    pub fn heartbeat(self, code: WatFnCode) -> Self {
        self.process_method(Method::Heartbeat, "heartbeat", code)
    }

    /// Add `canister_global_timer` exported function to the WAT canister.
    pub fn global_timer(self, code: WatFnCode) -> Self {
        self.process_method(Method::GlobalTimer, "global_timer", code)
    }

    /// Add `canister_update <name>` exported function to the WAT canister.
    pub fn update(self, name: &str, code: WatFnCode) -> Self {
        self.process_method(Method::Update, name, code)
    }

    /// Add `canister_query <name>` exported function to the WAT canister.
    pub fn query(self, name: &str, code: WatFnCode) -> Self {
        self.process_method(Method::Query, name, code)
    }

    /// Add `canister_composite_query <name>` exported function to the WAT canister.
    pub fn composite_query(self, name: &str, code: WatFnCode) -> Self {
        self.process_method(Method::CompositeQuery, name, code)
    }

    /// Build the WAT canister.
    pub fn build(mut self) -> String {
        let mut rendered_functions = Vec::new();

        // Drain the ASTs to compute rendering
        let funcs: Vec<WatFunc> = self.functions.drain(..).collect();

        for func in funcs {
            let declaration = func.export_declaration();

            // Perform single-pass rendering over the function's AST
            let mut state = RenderState {
                next_loop_id: 0,
                memory: &mut self.memory,
                memory_offset: &mut self.memory_offset,
                instructions: Vec::new(),
            };

            let top_level_locals = RenderState::count_loops(&func.code.calls);
            state.process_calls(&func.code.calls, STEP);

            // Piece together the exact Text block.
            let locals: String = (0..top_level_locals)
                .map(|i| format!("{INDENT}{STEP}(local $loop_counter_{i} i32)"))
                .collect::<Vec<_>>()
                .join("");

            let body = state.instructions.join(&format!("{INDENT}{STEP}"));

            if !body.is_empty() {
                rendered_functions.push(format!(
                    "({declaration}{locals}{INDENT}{STEP}{body}{INDENT})"
                ));
            } else {
                rendered_functions.push(format!("({declaration}{locals})"));
            }
        }

        let functions_block = rendered_functions.join(INDENT);

        let mut data_entries: Vec<_> = self.memory.into_iter().collect();
        data_entries.sort_by_key(|&(_, offset)| offset);

        let data_block = data_entries
            .into_iter()
            .map(|(message, offset)| {
                format!(
                    r#"(data (i32.const {}) "{}")"#,
                    offset,
                    format_wasm_string(&message)
                )
            })
            .collect::<Vec<_>>()
            .join(INDENT);

        format!(
            r#"
        (module
            ;; Import functions
            (import "ic0" "stable_grow" (func $ic0_stable_grow (param i32) (result i32)))
            (import "ic0" "stable_read" (func $ic0_stable_read (param i32 i32 i32)))
            (import "ic0" "global_timer_set" (func $ic0_global_timer_set (param i64) (result i64)))
            (import "ic0" "performance_counter" (func $ic0_performance_counter (param i32) (result i64)))
            (import "ic0" "debug_print" (func $ic0_debug_print (param i32) (param i32)))
            (import "ic0" "trap" (func $ic0_trap (param i32) (param i32)))

            ;; Define functions
            (func $_wait (param $instructions i64)
                ;; Calculate the instruction limit
                (local $limit i64)
                (local.set $limit (i64.add (call $ic0_performance_counter (i32.const 0)) (local.get $instructions)))
                (loop $loop
                    (if (i64.lt_s
                            (call $ic0_performance_counter (i32.const 0))
                            (local.get $limit))
                        (then
                            ;; Placeholder instruction for simulating work in a reserved memory block
                            (memory.fill (i32.const {WAIT_SCRATCHPAD_START}) (i32.const 0) (i32.const {MEMORY_FILL_MAX}))
                            (br $loop)
                        )
                    )
                )
            )
            {functions_block}

            ;; Define memory
            (memory $memory 1)
            (export "memory" (memory $memory))

            ;; Initialize memory with data
            {data_block}
        )"#
        )
    }

    /// Build the Wasm for the WAT canister.
    pub fn build_wasm(self) -> Vec<u8> {
        wat::parse_str(self.build()).unwrap()
    }

    fn process_method(mut self, method: Method, name: &str, code: WatFnCode) -> Self {
        let name = name.to_string();
        // It's OK to use linear search here because this is a test util
        // and the number of functions is small.
        if self.functions.iter().any(|f| f.name == *name) {
            panic!("Method '{method:?}' with the name '{name}' already exists");
        }
        self.functions.push(WatFunc { method, name, code });
        self
    }
}

impl Default for WatCanisterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Mutable internal state for lowering Wasm AST calls to strings
struct RenderState<'a> {
    next_loop_id: usize,
    memory: &'a mut HashMap<Vec<u8>, i32>,
    memory_offset: &'a mut i32,
    instructions: Vec<String>,
}

impl<'a> RenderState<'a> {
    /// Count the exact number of Nested/Successive Loops required to allocate local descriptors.
    fn count_loops(calls: &[FnCall]) -> usize {
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

    fn process_calls(&mut self, calls: &[FnCall], indent: &str) {
        for call in calls {
            match call {
                FnCall::StableGrow(new_pages) => self
                    .instructions
                    .push(format!("(drop (call $ic0_stable_grow (i32.const {new_pages})))")),
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
                FnCall::Wait(instructions) => self
                    .instructions
                    .push(format!("(call $_wait (i64.const {instructions}))")),
                FnCall::Loop(count, inner_calls) => {
                    let id = self.next_loop_id;
                    self.next_loop_id += 1;

                    self.instructions.push(format!("(local.set $loop_counter_{id} (i32.const {count}))"));
                    self.instructions.push(format!("(loop $loop_label_{id}"));

                    let inner_indent = format!("{}    ", indent);
                    self.instructions.push(format!("{inner_indent}(if (i32.gt_u (local.get $loop_counter_{id}) (i32.const 0))"));
                    self.instructions.push(format!("{inner_indent}    (then"));

                    // Render inner code logic
                    self.process_calls(inner_calls, &format!("{inner_indent}        "));

                    // Step control block
                    self.instructions.push(format!("{inner_indent}        (local.set $loop_counter_{id} (i32.sub (local.get $loop_counter_{id}) (i32.const 1)))"));
                    self.instructions.push(format!("{inner_indent}        (br $loop_label_{id})"));

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
fn format_wasm_string(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 3);
    for &b in data {
        if b.is_ascii_graphic() && b != b'\\' && b != b'"' || b == b' ' {
            s.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut s, "\\{:02x}", b);
        }
    }
    s
}
